# Execution plan: two agents, Clockchain-operated, on AWS

**Date:** 2026-08-07 · Supersedes nothing — this is the *execution-grade* expansion of
[two-agent-build.md](two-agent-build.md) (which holds the locked decisions D1–D5 and the
verified infrastructure map). Where detail here conflicts with that document, this one wins.

**Written for a weaker executor.** Every design decision is already made. Every task says
what to do, how to verify it, and what to do when verification fails. Do not redesign, do
not "improve," do not skip verification steps. When a STOP trigger fires, stop and write
what you found into `HANDOFF.md` — do not improvise past it.

---

## §0 — The executor contract

1. **Two tracks run in parallel: Track A (code) and Track B (migration).** Within a track,
   tasks are strictly sequential. Never start a task before the previous task's *Verify*
   block passes.
2. **After every task**, run the full check before committing:
   ```bash
   npm run verify
   ```
   (= full test suite + all structural invariants). It must end green. If a task doesn't
   touch this repo (Track B mostly doesn't), run it anyway before any commit here.
3. **One commit per task**, message style matching `git log` (lowercase, plain, says what
   and why in one line). Commit only what the task changed.
4. **Never touch:** `src/core/verdict.mjs` (the single emission site), the canonical
   profile (`src/core/canonical*.mjs`), existing passing tests (except where a task
   explicitly says to extend one), `scripts/check-invariants.sh` (if an invariant fails,
   your change is wrong — fix the change, never the check).
5. **Legacy `npm run demo` must work at every commit.** This is a hard constraint from
   the build plan (demo continuity). Nothing in Track A or B may break it before P4.
6. **Do not write the ten-letter verifier-outcome literal** (the one that starts with
   AUTH) in any file under `src/`, `bin/`, or `scripts/` — not even in comments. The
   containment invariant is a blunt file-level grep, deliberately. Print
   `verdict.outcome`; never name it.
7. **When stuck** (a Verify block fails twice, a STOP trigger fires, or reality
   contradicts a Fixed Fact in §1): stop, append a dated note to `HANDOFF.md` §Blockers
   with exactly what you ran, what you expected, and what you saw. Do not push a broken
   state.

---

## §1 — Fixed facts (verified 2026-08-07; do not rediscover, do trust)

**Repo layout that matters:**

| Thing | Where | Notes |
|---|---|---|
| Operator (host+payer fused, legacy) | `bin/operator.mjs` (537 lines) | The donor for the host. Untouched until P4. |
| Requestor kit | `bin/requestor.mjs` | The template for the payer kit. |
| Relay server / entry / client | `src/relay/server.mjs`, `bin/relay.mjs`, `src/relay/client.mjs` | Server exports handlers; `bin/relay.mjs` listens. |
| Session helpers | `src/roles/session.mjs` | `buildMandate`, `buildDescriptor`, `postNext`, `fetchDiscovery`, `readDiscovery`, `roleAlreadySeated`, `say`, `stop`. |
| Certificate | `src/core/result.mjs` (`buildSignedResult`, `verifyResultEnvelope`) | Emitter + verifier exist and are live-tested. |
| Verifier | `src/core/verdict.mjs` → `verifyBilateralAuthorization` | The ONLY emission site. |
| Role state machines | `src/core/roles-core.mjs` → `runPayerRole`, `runPayeeRole` | |
| Monitor snapshots | `src/monitor/snapshot.mjs` → `buildSnapshot`, `STATUSES`, `FAILED_STAGE`, `REASON_CODES` | Exact-key validated on the relay. |
| MCP client | `src/core/clockchain.mjs` → `createMcpClient`, `mintDemoToken` | |

**Two registry constants — the trap that already fired once:**
- `src/core/constants.mjs` → `REGISTRY_ADDRESS` is **checksummed** (mixed case). Use for
  viem contract calls only.
- `src/core/descriptor.mjs` → `REGISTRY_ADDRESS` (import-aliased `CANONICAL_REGISTRY` in
  operator.mjs) is **lowercase**. Use for anything inside a signed/canonical document.
  The canonical profile rejects checksummed addresses at signing time.

**Canonical profile rules:** strings only (no JSON numbers), printable ASCII ≤ 256 chars
per string, lowercase 0x addresses. All ids (`agentId`, `blockHeight`, timestamps) travel
as strings.

**Relay behavior (verified in source):**
- Messages: role and kind are free-form strings. The relay validates size
  (`MAX_MESSAGE_BODY_BYTES`) and shape, never semantics, never signatures. Posting with
  role `"host"` or a new kind like `"anchor_report"` requires **no relay change**.
- Evidence: role-gated by `PARTY_ROLES = ["payer", "payee"]` (`src/core/evidence.mjs:38`).
  Both roles already work. The requestor uploads as `"payee"`; a payer kit uploads as
  `"payer"` with zero relay changes.
- Result endpoint (`GET/PUT /v1/sessions/{sid}/result`) is deployed and live-tested.
- The relay is **untrusted by design**. Never add signature checks to it. Shape-only.

**Message filtering in kits:** `awaitKind` in `bin/requestor.mjs` filters by `kind` only,
not by role — new message roles won't confuse it. BUT its `funding_record` handler treats
a record funding a *different* address as "another requestor won" and stops. See task A3.

**MCP base URL:** `src/core/constants.mjs` hardcodes `https://mcp.clockchain.network`.
There is NO env override, and you must not add one to `src/core` (port-purity discipline).
Track B's cutover sequencing (§4) is designed around this fact.

**Deployed infrastructure:**
- Relay: AWS Lightsail `44.249.47.220`, instance `handshake-relay-1`, code at
  `/opt/handshake/app`, service `handshake-relay`, SSH via
  `ssh -i ~/.ssh/handshake-relay.pem ubuntu@44.249.47.220`.
- MCP: GCP Cloud Run behind `mcp.clockchain.network` (Google Frontend, `136.68.167.2`).
- Chain node: `node.clockchain.network` = `54.176.69.37`, AWS but **not** in Yang's
  account. External. Do not touch, do not plan around touching it.
- AWS account: `570035913370`, IAM user `Yang`, CLI signed in. Region default us-west-2.
- DNS: GoDaddy (`ns19/ns20.domaincontrol.com`). Every DNS change is a Yang action.
- MCP source: `github.com/thetangstr/clockchain-developer-tools` (Dockerfile,
  `deployment.md`, `CLOUD-RUN.md`, CI). Not cloned locally yet.
- Token minting: rate-limited **10/hour per IP**. The relay box has its own quota
  (RUNBOOK §troubleshooting has the exact remote-mint command).

**Timing rules (each one is a scar):**
- Never stamp a timestamp in the future. `createdAtMs === issuedAtMs`. Observed margins
  against Clockchain anchoring are sub-second (once negative).
- Human-paced waits are 45 minutes; machine-paced constants in `src/` must be on the
  invariant script's allowlist (17 names). New `*_MS` constants in `src/` will trip the
  invariant until classified — prefer putting kit-local waits in `bin/`.
- The authorization window is 600 s from PROPOSED. Everything human-paced (funding,
  registration, both parties ready) happens BEFORE the first anchor.

---

## §2 — Target choreography (what the three processes say to each other)

Roles: **host** = `bin/clockchain-host.mjs` (Clockchain's side: session lifecycle, funding,
descriptor signing, verifier, certificate — holds treasury + ed25519 key, never a party
key). **payer** = `bin/payer.mjs` (new kit). **requestor** = `bin/requestor.mjs` (existing
kit, minimally patched).

| # | Author | Kind (role tag) | Body essentials | Consumer waits on it |
|---|---|---|---|---|
| 0 | host | *(session + discovery doc)* | as today | both kits fetch discovery |
| 1 | payer | `identity_ready` (`payer`) | `{address}` | host |
| 2 | requestor | `identity_ready` (`requestor`) | `{address}` | host |
| 3 | host | `funding_record` (`host`) ×2 | `{funded, role, paymentMoved:false}` — **role names which seat was funded** | each kit, filtered by `funded === own address` |
| 4 | payer | `party_ready` (`payer`) | `{address, agentId}` | host + *(payer's counterpart info source for requestor: msg 5)* |
| 5 | requestor | `party_ready` (`requestor`) | `{address, agentId}` | host, payer |
| 6 | payer | `mandate` (`payer`) | `{common, expiresAtMs, issuedAtMs, mandateEnvelope, sessionUuid, paymentMoved:false}` — same shape as today | requestor, host |
| 7 | requestor | `payment_request` (`requestor`) | `{requestEnvelope}` | host |
| 8 | host | `handshake_required` (`host`) | `{descriptorEnvelope, repositoryPublicKey, paymentMoved:false}` | both kits |
| 9 | requestor | `watching` (`requestor`) | | payer (opens the window only after this) |
| 10 | *(both kits run their roles → three anchors on Clockchain)* | | | |
| 11 | payer | `anchor_report` (`payer`) | the three anchors, board-shaped; **narration only, untrusted** | host (guarded, best-effort) |
| 12 | both kits | *(evidence upload: payer as `"payer"`, requestor as `"payee"`)* | | host polls both |
| 13 | host | *(runs verifier → PUT result)* | signed `handshake-result/v1` | both kits GET + verify + save |

Notes that prevent rework:
- Messages 1/2 and 4/5 can arrive in either order; the host distinguishes by `role` on the
  message. Steps 6–9 are strictly ordered by their own data dependencies.
- The **mandate body shape is unchanged** — only its author moves from operator to payer
  kit. The requestor's consumption code (`terms.body.common` etc.) needs no change.
- The payer learns `requestorAddress`/`requestorAgentId` by polling the mailbox for
  messages 2 and 5 itself. There is no roster document; the mailbox is the roster.
- The host learns `common`/`sessionUuid` for `buildDescriptor` from message 6's body —
  exactly the way the requestor already reads them.
- Seating: each kit checks `roleAlreadySeated(messages, ownRole)` before posting
  message 1/2 (`src/roles/session.mjs:479`, role-aware, already shipped and tested).
- The certificate's party references are built from `DESCRIPTOR_CHAIN_ID` +
  `CANONICAL_REGISTRY` (lowercase) — carry the pattern from `bin/operator.mjs:492`
  verbatim, including passing the whole guarded try/catch structure.

---

## §3 — Track A: sever the host, build the payer kit

### A1 — Preflight reading (no code changes)

Confirm the fixed facts still hold. Run each; expected result in parentheses:

```bash
grep -n "roleAlreadySeated" src/roles/session.mjs bin/requestor.mjs   # (exported + used)
grep -n "PARTY_ROLES" src/core/evidence.mjs | head -2                  # (["payer","payee"])
grep -rn "putResult\|getResult" src/relay/client.mjs | head -4         # (both exist)
node -e 'import("./src/relay/server.mjs").then(()=>console.log("server loads"))'
sed -n '110,145p' bin/requestor.mjs                                    # (read the funding_record handler in full)
```

Also read, once, end to end: `bin/operator.mjs`, `bin/requestor.mjs`,
`src/roles/session.mjs`. You are about to split the first and mirror the second.
**Verify:** you can state, without looking, which of the operator's stdout writes belong
to the host vs the payer. **Commit:** nothing.

### A2 — `buildMandate` accepts an injected `issuedAtMs`

**Why:** the payer kit must stamp the mandate from Clockchain's own `get_timestamp`, not
the local clock (closes the residual clock-skew class — a laptop clock one second fast
already killed live runs once via `createdAtMs`).

1. In `src/roles/session.mjs`, give `buildMandate` an optional `issuedAtMs` param
   (default: exactly today's behavior). It must remain a string-safe integer ms value;
   `expiresAtMs` derives from it the same way it does today.
2. Find the MCP client's timestamp call: `grep -n "get_timestamp\|getTimestamp" src/core/clockchain.mjs`.
   Note the exact method name and return shape for A5 — do not guess it there.
3. New test in `test/` (own file): injected `issuedAtMs` flows into the mandate envelope;
   omitted param preserves current behavior byte-for-byte against a pinned fixture.

**Verify:** `npm run verify` green. **Commit:** `mandate: issuedAtMs can come from the ledger clock`

### A3 — Role-tagged funding records; kits skip the other seat's record

**Why (a live-run killer found in planning):** the requestor's `funding_record` handler
treats the first record as its own and stops when `funded` names another address ("another
requestor won"). The host funds TWO seats, so a payer-funding record arriving first would
kill an innocent requestor.

1. Producer: the host (A4) will post `funding_record` with body
   `{funded, role: "payer"|"requestor", paymentMoved: false}`. (The legacy operator is NOT
   changed — its single record continues to have no `role` field.)
2. Consumer, in `bin/requestor.mjs`: on a `funding_record` whose `funded` ≠ own address —
   if `body.role` is present and ≠ `"requestor"`, **skip it and keep waiting** (it's the
   other seat's funding); if `body.role` is absent or `=== "requestor"`, stop as today
   (a rival requestor really did win). Keep waiting means: continue the same awaitKind
   loop for the next `funding_record`, same deadline.
3. Tests (own file): (a) payer-tagged record for another address is skipped and a later
   requestor-tagged record for own address proceeds; (b) untagged record for another
   address still stops — the legacy race outcome is pinned; (c) requestor-tagged record
   for another address stops.

**Verify:** `npm run verify` green; then one legacy live check — `npm run demo` +
a requestor against it still reaches the verifier (the operator's untagged record must
still be accepted as own-funding by the patched requestor). **Commit:**
`funding records name their seat; kits skip the other seat's record`

### A4 — `bin/clockchain-host.mjs`

Copy `bin/operator.mjs` to `bin/clockchain-host.mjs`, then transform. Enumerated:

**Remove** (payer-side, moves to the kit in A5): `payerKey`/`payerAccount` and everything
touching them; `registerIdentity(payerAccount, …)`; `buildMandate` call and mandate
posting; `runPayerRole` and its output directory; the `watching` wait; the payer evidence
directory being local-only.

**Keep** (host-side): treasury + token loading; per-session ed25519 keypair + `repositoryPublicKey`;
session creation, discovery publish, self-check, read-back; the whole monitor block
(`createMonitorState` … `publishSnapshot`, `say`/`stop` shadows); `awaitKind`; the
descriptor build + `createSignedEnvelope` + `handshake_required` post (role `"host"`);
the verifier call; the fully-guarded certificate section (verbatim, including the
comment about why the whole section is guarded); the `runs/session-*.json` persist.

**Add:**
1. **Two-seat intake.** Await `identity_ready` from each role (either order; use the
   message `role` field). On each: fund that address (same 0.01 ETH pattern), post
   `funding_record` role `"host"` with `{funded, role: <seat>, paymentMoved: false}`.
   Then await both `party_ready` messages; record identities into `monitorState.identities`
   keyed the way the operator does (`payer` / `payee` — the requestor seat is `payee`).
2. **Mandate + request intake.** Await kind `mandate` (from the payer kit); minimally
   shape-check (`body.common`, `body.sessionUuid`, `body.mandateEnvelope` present — the
   verifier does the real checking later). Await kind `payment_request`. Build the
   descriptor from the mandate body's `common`/`sessionUuid` + both envelopes, sign, post
   `handshake_required`.
3. **Anchor narration.** New small module `src/monitor/anchor.mjs`: move copies of
   `transitionToAnchor`, `signerOf`, `termsOf` from operator.mjs (leave operator.mjs
   untouched — duplication is accepted until P4 retires it; say so in a comment). Host
   awaits kind `anchor_report` (bounded, ~12 min budget — role runs are machine-paced but
   sit behind human-paced setup), maps the three reported anchors into
   `monitorState.anchors`, and narrates ACCEPTED/ACKNOWLEDGED stages. **The entire
   mapping is wrapped in try/catch** — a malformed report degrades the board, never the
   run. If the report never arrives, skip narration; the verifier's `verdict.transitions`
   still populates anchors at the end.
4. **Two-sided evidence.** Poll `relay.getEvidence` for BOTH `"payer"` and `"payee"` in
   one loop (deadline 5 min from `anchor_report` arrival or from `handshake_required` + 12
   min if it never came). Write each into its own temp directory exactly the way the
   operator writes the payee's. Missing either at the deadline → session fails `MISSING`.
5. **Verifier + certificate:** exactly the operator's code, with `payerDirectory` now the
   downloaded payer evidence. Party addresses/agentIds for the certificate come from the
   observed `identity_ready`/`party_ready` bodies.
6. **The always-open loop (D3).** Wrap everything after boot (treasury/token load) in
   `runOneSession()`. In the host, the `stop()` shadow publishes the FAILED snapshot and
   **throws** a `SessionEnded` error instead of exiting the process. The main loop:
   `while (true) { try { await runOneSession() } catch (e) { log it } ; small cooldown }`.
   Boot-time failures (missing keystore, unreadable token) remain fatal before the loop.
   EXPIRED (nobody joined in 45 min) therefore auto-reopens — which is D3.
7. Wire `npm run host` in package.json mirroring the `demo` script's env defaults.

**Do not** write the verifier-outcome literal anywhere in the file, comments included.

**Verify:** `npm run verify` green (invariants scan `bin/`); `node bin/clockchain-host.mjs`
against a local relay (`node bin/relay.mjs`) boots, publishes a session, and heartbeats
while waiting. Kill it; restart; a fresh session opens (loop works). **Commit:**
`host: Clockchain's side is its own process`

### A5 — `bin/payer.mjs`

Mirror `bin/requestor.mjs` structure and tone. The full sequence:

1. Input: one URL (`--discovery-url`, supporting the stable `/current` form the same way
   the requestor does). Optional `--relay-url` NOT needed — the discovery document carries
   `relayUrl`.
2. `fetchDiscovery` → `readDiscovery` validation → refuse bad invitations with the same
   sentences the requestor uses.
3. Seating: `roleAlreadySeated(messages, "payer")` → stop `ROLE_ALREADY_BOUND` (mirror the
   requestor's two-guard structure: pre-check, then the funding record is the tiebreak).
4. Fresh key: `generatePrivateKey()`/`privateKeyToAccount`. Post `identity_ready`
   role `"payer"` with lowercase address.
5. Await `funding_record` with `funded === own address` (skip other-seat records per A3
   semantics — implement the same tolerant filter here from day one).
6. Self-register ERC-8004 (copy the requestor's registration section — own wallet signs
   `register`, parse agentId from logs, checksummed `REGISTRY_ADDRESS` from
   `constants.mjs` for the viem call). Post `party_ready` role `"payer"`.
7. Poll mailbox for the requestor's `identity_ready` + `party_ready` → counterparty
   address + agentId (45-min human-paced budget).
8. Mint own token: `mintDemoToken({})` (the requestor already does this — same call).
9. `issuedAtMs` from the ledger: the `get_timestamp` method found in A2. Then
   `buildMandate({ …, issuedAtMs })`, sign locally, post the `mandate` message —
   body shape identical to the operator's today.
10. Await `handshake_required`. **Check `body.repositoryPublicKey ===
    discovery.operatorPublicKey`** — refuse the session on mismatch (a descriptor signed
    by a key the invitation never named is the realistic substitution attack). Note: the
    requestor should get this same check in P4's cleanup; do not patch it now.
11. Await `watching` (the requestor's signal). Only then `runPayerRole` with own
    `signMessage`, own token client, `ownerOf` via the public client — the parameter shape
    is in `bin/operator.mjs:399`.
12. Post `anchor_report` (role `"payer"`): the three transitions mapped with
    `src/monitor/anchor.mjs` helpers (it has `RELAY_URL` from discovery for the
    explorer links). Best-effort: wrap in try/catch, never fail the run over narration.
13. Upload payer evidence: mirror the requestor's upload, role `"payer"`.
14. Fetch the certificate: poll `relay.getResult` up to 5 min,
    `verifyResultEnvelope(envelope, { expectedPublicKey: discovery.operatorPublicKey })`,
    save `closing-certificate.json` beside the evidence, print the checker's verdict as
    the checker's word — copy the requestor's certificate section including its
    fail-closed refusal sentence.
15. Exit **without naming an outcome of its own** — the kit reports what the certificate
    says or that it didn't arrive; it never adjudicates.

**Verify:** `npm run verify` green; then the G0 gate (A7) is the real test. A unit test
file for anything extracted as a pure function (at minimum: the funding-record filter if
shared, the discovery-pubkey mismatch refusal if expressible purely). **Commit:**
`payer: a kit of its own, symmetric to the requestor`

### A6 — Local gate **G0**

Four terminals (or one tmux script if you prefer — not required):

```bash
node bin/relay.mjs                                            # terminal 1 (local relay :8080)
HANDSHAKE_RELAY=http://127.0.0.1:8080 npm run host            # terminal 2
node bin/payer.mjs --discovery-url http://127.0.0.1:8080/...  # terminal 3 (URL from host output)
node bin/requestor.mjs --discovery-url http://127.0.0.1:8080/... # terminal 4
```

**Pass criteria (all of them):**
- The verifier's outcome prints on the **host**, and `paymentMoved: false`.
- The certificate is fetched, verified, and saved by **both** kits.
- Neither kit named an outcome of its own.
- After the run, the host **reopens a fresh session by itself** (D3), and the monitor
  `current` alias follows it.
- `npm run verify` still green; legacy `npm run demo` still works (run it once).

This burns testnet gas (4 × 0.01 ETH funding: 2 seats × registration) and two token
mints — that is expected and fine. **Commit:** nothing (gate only) — but record the
session id and block heights in `HANDOFF.md` §Evidence.

### A7 — Deploy + live gate **G1**

1. Deploy the updated kit to the relay box (the relay itself needs no code change, but
   the box's kit copy is used for remote-driving):
   ```bash
   rsync -av --exclude .git --exclude keys --exclude runs --exclude node_modules \
     ./ ubuntu@44.249.47.220:/opt/handshake/app/ -e "ssh -i ~/.ssh/handshake-relay.pem"
   ssh -i ~/.ssh/handshake-relay.pem ubuntu@44.249.47.220 \
     "cd /opt/handshake/app && npm ci --omit=dev && sudo systemctl restart handshake-relay && sleep 2 && curl -s localhost:8080/healthz"
   ```
2. Run the host on the laptop against the deployed relay (`npm run host`), payer kit from
   the relay box (`ssh … node bin/payer.mjs --discovery-url <url>`), requestor from the
   laptop — three genuinely separate machines/processes.
3. **Race check:** start a second payer against the same session. It must stop
   `ROLE_ALREADY_BOUND` (or lose the funding-record tiebreak) with nothing spent beyond
   at most one funding TX — verify the second payer registered nothing.

**Pass:** same criteria as G0, on the real relay, plus the race check, plus the
monitor page at `http://44.249.47.220:8080/monitor/current` shows the run correctly
(receipts, identities, no `[object Object]`, verdict appears only at the end).
**Commit:** nothing; update `HANDOFF.md` §Evidence.

### A8 — The payer handoff document

`docs/run-the-payer.md`, in the exact register of `docs/for-ken.md`: addressed to the
human, states plainly it's a testnet demo with no real money, lists optional pre-reqs
(node 22, git), gives the one command with the one URL. **Do not iterate persuasion
language** — if an agent refuses to run it, the document explains to the *human* what the
kit does and lets them decide (that lesson is already paid for). **Commit:**
`docs: how to run the payer side`

---

## §4 — Track B: migrate the MCP to AWS (runs in parallel with Track A)

**Prime directive: at every moment, `npm run demo` works.** GCP serves until the DNS flip;
the flip is reversible; GCP stays warm afterward until a full demo passes.

### B0 — Clone and inventory

```bash
cd ~/Documents/Projects && gh repo clone thetangstr/clockchain-developer-tools
```

Read `deployment.md`, `CLOUD-RUN.md`, the Dockerfile, and the server entrypoint. Fill in
this table in `HANDOFF.md` §Migration-inventory (every row, even if the answer is "none"):

| Question | Answer |
|---|---|
| Language/runtime + listen port | |
| How does it reach the chain node (`node.clockchain.network`)? Pull or push? | |
| Where do token quotas live (memory / file / external store)? | |
| Where do receipts/ledger ids live? | |
| Env vars + secrets the container needs (names, where GCP stores them) | |
| Does it use ANY GCP-managed service (Firestore, GCS, Cloud SQL, Memorystore, Pub/Sub)? | |
| Does it stream (SSE/websocket) on the MCP endpoint? | |
| Health endpoint | (`/health` is known to answer unauthenticated) |

**STOP triggers:** any GCP-managed data service in the yes column, or the node *pushing*
to the MCP (inbound from an external box changes the network design). Write it up; the
target below only holds for a self-contained container.

### B1 — Locked target (decided; do not re-litigate)

**One EC2 instance** in `us-west-2`, account `570035913370`:
- `t3.small`, Ubuntu 24.04 LTS, 20 GB gp3, Elastic IP.
- IAM instance profile with `ssm:GetParameter` on `/clockchain/mcp/*` only.
- Secrets in **SSM Parameter Store** (SecureString) under `/clockchain/mcp/<NAME>`,
  fetched at boot into env / 0600 files by the compose wrapper.
- Docker + docker compose. Services: `mcp` (the container), `caddy` (TLS terminator,
  ports 80/443). Compose `restart: unless-stopped`; a systemd unit runs
  `docker compose up -d` on boot.
- Security group: 22 (Yang's IP), 80, 443. Nothing else.

Why not App Runner (SSE/streaming behavior is a known risk for MCP transports), why not
ECS (more moving parts than this workload justifies), why EC2 over Lightsail (instance
profiles → no long-lived AWS keys on the box). The upgrade path to ECS exists later; this
is the right size now.

### B2 — Provision

```bash
aws ec2 create-key-pair --key-name clockchain-mcp --query KeyMaterial --output text \
  > ~/.ssh/clockchain-mcp.pem && chmod 600 ~/.ssh/clockchain-mcp.pem
# security group, instance with Ubuntu 24.04 AMI, IAM role/profile, Elastic IP:
# script the exact calls; record every id in HANDOFF.md §Migration-inventory.
```

User-data installs docker + compose plugin. Verify: SSH in, `docker run hello-world`,
`aws ssm get-parameter --name /clockchain/mcp/PING` (after creating a dummy param) works
**via the instance role** (no credentials file on the box — check `~/.aws` is absent).

### B3 — Deploy side-by-side, behind a test hostname

1. Ask Yang for **one GoDaddy visit** doing two things: (a) add `mcp-aws.clockchain.network`
   A-record → the Elastic IP; (b) lower TTL on the existing `mcp` record to 600.
   (Both now, so the cutover visit later is a single record flip.)
2. On the box: clone the repo, build the image, run compose. Caddy serves
   `mcp-aws.clockchain.network` with auto-TLS (needs (a) resolving first).
3. Secrets: create each SSM parameter the inventory found; wire them in.

### B4 — Parity verification (service level, pre-cutover)

Script it (in `clockchain-developer-tools`, e.g. `scripts/parity-check.mjs`): for each of
`/health`, token mint, `get_timestamp`, `get_block` (a known height), `log_action`
(+ read it back via `get_log_entry`) — call **both** `mcp.clockchain.network` (GCP) and
`mcp-aws.clockchain.network`, compare response shapes and semantics. Token quota behavior
must match (mint 2, see the count move). **Pass:** every row same-shaped; a logged action
via AWS is readable via GCP's path or the node (proves both front the same ledger). If
logged actions do NOT appear across both, STOP — the service holds state the inventory
missed.

### B5 — Cutover (gate **GM**)

1. Confirm TTL 600 has been live ≥ the old TTL's duration. Pick a no-demo window.
2. Yang flips `mcp.clockchain.network` A-record → the Elastic IP. Caddy config already
   lists `mcp.clockchain.network` as a second site; on the first request post-flip it
   obtains that cert via HTTP-01 automatically (expect a ≤ 2-min TLS gap; acceptable, we
   are in a no-demo window; the GCP side remains untouched for instant rollback).
3. Verify: `dig +short mcp.clockchain.network` = Elastic IP from a public resolver;
   `curl https://mcp.clockchain.network/health` clean; re-run the parity script with both
   names (they now hit AWS — GCP is reached no other way, which is the point).
4. **GM:** `npm run preflight` then a full `npm run demo` handshake run end-to-end, with
   the hostname resolving to AWS. Record session id + blocks in `HANDOFF.md` §Evidence.
5. **Rollback (if GM fails):** flip the record back (TTL 600 → minutes), diagnose on the
   test hostname, retry later. GCP is not decommissioned until Yang separately says so.

### B6 — Fold the relay (only after GM is green)

Bar: "makes sense," not completionism. Sequence if pursued:
1. Yang adds `relay.clockchain.network` → currently `44.249.47.220`. Then re-point the
   default in `package.json` and the runbook at the hostname — after that the relay's IP
   can move without breaking the "permanent" monitor URL (which today embeds the raw IP).
2. Move the relay container onto the MCP box's compose file; rsync `/opt/handshake` disk
   journal across during a brief freeze; flip the `relay` record.
3. If effort exceeds half a day or the journal move looks risky, **defer** — the relay
   staying on Lightsail under the same account is an acceptable end-state. Write the
   decision down either way.

---

## §5 — After the tracks (P2 → P3 → P4, gated on Track A + B both green)

**P2 — Host onto the AWS box.** Third compose service `host` from a small Dockerfile in
this repo. Secrets (`funding-wallet.json`, funding password, clockchain token) into SSM
under `/clockchain/host/*`, materialized as 0600 files at container start (the invariant
allows files-or-env only; no cloud-credential-store references in code). `npm run host`
stays as the local/dev path. **G2:** a full run with no process on the laptop; the host
loop survives a `docker restart`.

**P3 — Handshake tools in the MCP server** (in `clockchain-developer-tools`). Contract:
- `handshake_status(sessionId?)` → stage + what's needed next for the caller's role.
- `handshake_join(role)` → discovery info for the open session.
- `handshake_next(sessionId, role)` → `{stage, bytesToSignHex, context}` — canonical bytes
  prepared server-side.
- `handshake_submit(sessionId, role, signatureHex)` → advances the state machine.
- `handshake_get_certificate(sessionId)` → the signed result envelope.
The server runs the role state machine against the relay; the party's EIP-191 signature is
the only client-side act. **The invariant to test for, not just claim: no party key ever
touches the server** — the tool schema has no key-shaped input, and a test proves a full
side completes with signing performed by the test harness locally. **G3:** an agent
configured with only `mcp.clockchain.network` + any EIP-191 signer completes a full side;
certificate fetched through the MCP.

**P4 — Board, page, cutover.** Board names the middle: "Clockchain — session host &
independent checker." Runbook + research page updated; requestor gains the
discovery-pubkey check from A5 step 10; `bin/operator.mjs` retired and the anchor-helper
duplication from A4 collapsed; a stranger-shaped dry run before announcing.

---

## §6 — Pitfall register (every one of these already happened, or was caught in planning)

1. **Two registry constants.** Checksummed (`constants.mjs`) for viem; lowercase
   (`descriptor.mjs`) for canonical documents. Mixing them threw at signing time *after* a
   live verdict had printed.
2. **Guard whole sections, not just their tails.** The certificate try/catch must cover
   construction AND publication — an exception between "verdict printed" and "certificate
   published" once demoted a verified run to Stopped.
3. **Never stamp the future.** `createdAtMs === issuedAtMs`; anchor margins are
   sub-second. Any "+1000ms for safety" style adjustment is the bug, not the safety.
4. **The first `funding_record` is not necessarily yours.** Two seats are funded now.
   Filter by `funded === own address` + the `role` tag; untagged records keep legacy
   semantics (A3).
5. **Exact-key schema validation cuts both ways.** New field on a snapshot/anchor/result →
   the relay validator must deploy BEFORE any producer emits it, or the board blanks while
   the protocol completes fine. (This plan adds no such fields — `anchor_report` is a
   message, not a snapshot. Keep it that way.)
6. **The containment invariant greps prose.** The verifier-outcome literal in a comment
   fails the build. Print `verdict.outcome`; never write the word.
7. **`predecessor` is a triple**, not a string. Any new board surface renders its
   `blockHeight`, or `[object Object]` reaches a projector again. 858 passing tests once
   agreed with the wrong fixture — pin new shapes against *live* payloads (gates G0/G1).
8. **All-tests-green is not deployed-and-working.** Every gate in this plan is a live run
   because fixtures once encoded the same wrong assumption as the code. Never claim a
   phase done from the suite alone.
9. **Token quota: 10 mints/hour/IP.** G0+G1 burn at least 4 (two kits × two gates).
   Rehearse accordingly; the relay box has an independent quota (RUNBOOK has the command).
10. **The relay adjudicates nothing.** Seating and funding tiebreaks are kit-side checks
    on untrusted mailbox data. Do not "fix" a race by making the relay referee.
11. **Narration must never outrank the run.** Snapshot publishing, anchor reports, board
    mapping: try/catch everything; a malformed report degrades the audience view only.
    And the verdict field is set from the verifier's return, in exactly one place.
12. **`Date.now()` in a kit vs Clockchain's clock.** Party-signed timestamps come from
    `get_timestamp` where the design says so (payer mandate, A2/A5). Don't quietly revert
    to the local clock because it's easier to test.
13. **Deploy order: relay first, then producers.** Even when "the relay needs no change,"
    re-verify what's on the box before pointing new kits at it (`git log` on
    `/opt/handshake/app` vs local).
14. **DNS changes are Yang's hands.** GoDaddy has no API access here. Batch requests (B3
    does two in one visit); never plan a step that assumes you can flip a record yourself.
15. **Demo continuity is a gate condition, not a hope.** After every deploy or DNS step,
    run the legacy demo (or the new G0 equivalent post-P4) before calling the step done.

---

## §7 — Gate summary

| Gate | Track | Proves | Recorded where |
|---|---|---|---|
| G0 | A6 | Three local processes; host emits verdict + certificate; both kits verify it; host reopens (D3) | HANDOFF §Evidence |
| G1 | A7 | Same on real relay, three machines; payer race stops clean | HANDOFF §Evidence |
| GM | B5 | Full demo with `mcp.clockchain.network` on AWS; GCP out of the request path | HANDOFF §Evidence |
| G2 | P2 | Full run with no laptop process; host survives container restart | HANDOFF §Evidence |
| G3 | P3 | A full side via MCP tools + any EIP-191 signer; no party key server-side | HANDOFF §Evidence |
