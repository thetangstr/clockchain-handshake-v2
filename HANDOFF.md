# Handoff — two-agent build + AWS migration

**As of:** 2026-08-08 · **Branch:** `codex/handshake-build` · **914 tests pass and all
structural invariants hold.** The previous handoff (still valid for context, landmines §4, known
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
| Track A (A1–A8): host severance + payer kit + gates G0/G1 | ✅ complete — G0 and G1 live gates passed |
| Track B (B0–B6): MCP → AWS migration, gate GM | ✅ complete — GM green; B6 explicitly deferred under its plan branch |
| P2 / P3 / P4 | ✅ P2 + G2 complete · ⬜ P3 handshake tools next |

Both tracks are independent until P2. Work them in parallel if you can; if you must pick
one, Track B's first steps (B0–B2) have the longest external waits — start them first,
then do Track A while AWS/DNS steps settle.

## Environment facts you'll need on day one

- Run everything from `/Volumes/mac_studio_ssd/Projects/handshake`. `npm run verify`
  = tests + invariants; it gates every commit.
- `keys/` is gitignored and exists only on this laptop: funding wallet keystore +
  password file + Clockchain token. Treasury `0x157a377e…dce` had ~2.09 testnet ETH on
  08-04; **the new host funds two seats per run (~0.02 + gas)** — check balance in
  `npm run preflight` before gate runs.
- Relay box: `ssh -i ~/.ssh/handshake-relay.pem ubuntu@44.249.47.220`, code at
  `/opt/handshake/app`, service `handshake-relay`. Deploy = rsync + restart (exact
  commands in plan §A7).
- AWS: account `570035913370`, IAM user `Yang`, CLI signed in, region us-west-2.
- Clockchain MCP source: `github.com/thetangstr/clockchain-developer-tools`; migration
  branch/worktree is `codex/aws-migration` at
  `/Users/Kailor/.config/superpowers/worktrees/clockchain-developer-tools/codex-aws-migration`.
- Token mints: 10/hour/IP. Budget them around gates.

## External dependencies

1. **GoDaddy visit #1 complete** (plan §B3): `mcp-aws.clockchain.network` now resolves
   publicly to `34.209.199.138`; the production record remains on GCP at TTL 600.
2. **GoDaddy visit #2 complete** (plan §B5): `mcp.clockchain.network` now resolves to
   the Elastic IP at TTL 600. The exact rollback target remains GCP `136.68.167.2`.
3. **GCP stays billed/warm** through cutover and until a separate decommission decision.

## Blockers

*(append dated entries here; format: what you ran, what you expected, what you saw)*

- 2026-08-07 — A3 legacy live verification initially appeared blocked before
  session creation, but both earlier failures shared the same unsupported
  environment-variable mistake: `HANDSHAKE_KEYSTORE` is ignored by
  `bin/operator.mjs`; the operator needs `--keystore`. The corrected local-relay
  run used `HANDSHAKE_RELAY=http://127.0.0.1:18788
  CLOCKCHAIN_FUNDING_PASSWORD_FILE=/Volumes/mac_studio_ssd/Projects/handshake/keys/funding.password
  npm run demo -- --keystore
  /Volumes/mac_studio_ssd/Projects/handshake/keys/funding-wallet.json`, then
  `bin/requestor.mjs` against the local discovery URL. The legacy operator's
  untagged funding record was accepted, the requestor registered identity
  `9430`, and the verifier completed `AUTHORIZED` for session
  `4408a633-55f2-438a-8824-7c46bc4db255`. Blocks: proposal `3080317`,
  acceptance `3080337`, acknowledgment `3080339`.

- 2026-08-07 — B2's instance-role verification failed the plan's literal
  `~/.aws`-absent check twice. We ran
  `aws ssm get-parameter --name /clockchain/mcp/PING --region us-west-2` as
  `ubuntu` on `i-0d6765d143da7e1ea`, expected the role-authenticated read to
  leave `/home/ubuntu/.aws` absent, and saw AWS CLI v2.36.19 create only
  `/home/ubuntu/.aws/cli/cache/session.db` (20 KiB). No `credentials` or
  `config` file exists, and the live role policy is correctly limited to
  `ssm:GetParameter` on `/clockchain/mcp/*`. Track B is paused at B2 while the
  cache behavior is resolved without introducing long-lived credentials.
  **Resolved the same day:** AWS CLI v2's own `session.db` cache was the only
  writer. Bootstrap commit `11b9162` wraps the literal `aws` command with a
  disposable HOME, removes it on exit, and performs a fail-closed PING read as
  `ubuntu`. The same wrapper is live on `i-0d6765d143da7e1ea`; the exact PING
  read passed through the instance role and `/home/ubuntu/.aws` remained absent
  before and after. B2 is green.

- 2026-08-07 — B3 pre-deploy review found the live GCP service advertising
  temporary rate limits of 240 token mints/hour/IP and 300 MCP requests/minute,
  while the locked handoff/server default requires 10 mints and the deployment
  contract requires 30 requests. A header-only verification mint returned limit
  240. GCP was restored to `MCP_TOKEN_MINT_PER_HOUR=10` and
  `MCP_RATE_PER_MIN=30`; final revision `clockchain-mcp-00019-bqh` serves 100%
  of traffic, `/health` is green, and a fresh public token response reported
  limit 10. The AWS deploy assets pin the same limits, so B4 will compare the
  intended abuse ceilings rather than propagate the drift.

- 2026-08-07 — G0 attempt 1 stopped after both roles completed their ledger
  work but before host verification. We ran a local relay on `127.0.0.1:18789`,
  `npm run host`, `bin/payer.mjs`, and `bin/requestor.mjs` against session
  `9938db62-818b-4b5f-b2a6-a5fbfde9f67a`; expected the payer to post
  `anchor_report` and the host to fetch both evidence packages. The payer and
  requestor registered agents `9431` / `9432` and anchored blocks `3083414`,
  `3083435`, `3083437`, but the mailbox ended at `watching` with no
  `anchor_report`. Reproducing the report locally showed `postNext` failed
  `ENVELOPE_SIGNING`: board anchors contain numeric `blockTime`, while the
  canonical message preimage permits strings only. The report's best-effort
  catch intentionally hid that narration failure; the host therefore kept its
  12-minute report wait instead of beginning evidence verification. No
  certificate or verifier result was produced; the four processes were stopped.

- 2026-08-07 — B3's AWS containers are healthy, but public test-host TLS is
  blocked exactly where the plan predicts: `mcp-aws.clockchain.network` is still
  NXDOMAIN at Cloudflare's public resolver. Caddy's HTTP listener answers at the
  Elastic IP and redirects that hostname to HTTPS, then ACME reports the missing
  A/AAAA record. No certificate attempt was made for the production hostname.
  Add the waiting A record to resume B3 and run B4; do not change production DNS.
  **Resolved 2026-08-08:** the A record was added through GoDaddy's API, both
  authoritative and public resolvers returned `34.209.199.138`, and Caddy
  obtained the test-host certificate after its pre-DNS ACME backoff was reset.

- 2026-08-08 — B4 live parity passed `/health`, both token mints and quota
  movement, `get_timestamp`, and known-height `get_block`. The first AWS
  `log_action` then returned a tool error. The MCP container's direct `/getTime`
  read showed the shared Clockchain node at `0.0%` participation, so the
  truthful-anchoring guard refused the write before `/log`; an exact
  `searchAsset` reconciliation for `handshake-aws-parity-20260808-001` returned
  zero records. Twenty fresh condition polls over five minutes stayed at 0%
  while block height advanced from `3089947` to `3090227`. No retry or
  `allow_degraded` override was attempted. Resume B4 only after participation is
  greater than zero, then rerun the same idempotent gate.
  **Resolved 2026-08-08:** Yang explicitly made validator count non-blocking for
  this parity run. External-repo commit `fb4118b` added an operator-only
  `--allow-degraded true` option; the default still omits `allow_degraded` and
  fails closed. The same reconciled reference was rerun once and all eight
  parity rows passed. The two writes anchored at blocks `3090566` and `3090567`.

- 2026-08-08 — B5 attempt 1 flipped production DNS to `34.209.199.138`; public
  resolvers, HTTPS health, and the production-host certificate all passed. The
  first local post-cutover parity run stopped before writes because macOS still
  resolved the production name to cached GCP while the test name resolved to
  AWS. A fresh-source rerun from the relay box proved both names reached the
  shared AWS process and passed all eight rows; records
  `6b9257cf-7650-4d68-9dce-d42d087d42e2` / block `3091221` and
  `25f3a00a-462c-408d-82b2-a032d1d9af29` / block `3091222` anchored. GM then
  stopped at `npm run preflight`: the isolated worktree's `keys/*` entries are
  symlinks, which the hardened wallet loader correctly rejects. Per B5, the
  production A record was immediately rolled back to GCP `136.68.167.2` at TTL
  600 before diagnosis. The actual files in the primary repo are private regular
  files; rerunning the same preflight code with that repo as its data root passed
  all four checks (treasury `1.951` testnet ETH, ledger block `3091391`). Retry
  the cutover only after the rollback record has propagated; run GM from the
  primary data root or pass the real keystore/password paths explicitly.
  **Resolved 2026-08-08:** after authoritative and public rollback propagation,
  attempt 2 restored the AWS A record, the corrected GM preflight passed at
  ledger block `3091503`, and the full demo completed session
  `64dd961d-25e9-42d9-9dcb-7d30a55dc302`. Production remains on AWS.

- 2026-08-08 — P2's first service restart stopped the old compose stack, then
  the new wrapper rejected `/opt/clockchain-host/app` as “not a git checkout.”
  The dedicated checkout is owned by `ubuntu`, while systemd runs the wrapper
  as root without sudo's `SUDO_UID`; Git's ownership guard therefore rejected
  `rev-parse` before Docker could start. Production MCP health was briefly
  unavailable. We restored the stack with an exact-path temporary
  `safe.directory`, reproduced the difference between sudo-shaped and
  systemd-shaped environments, then removed the host-wide setting. External
  repo commit `c73a3a4` now passes `safe.directory` only to the three Git reads
  for the exact configured checkout. A second installer run brought MCP,
  Caddy, and host up; both public health endpoints are green. No persistent
  system or global Git exception remains.

## Evidence

*(gate results land here: gate id, date, session id, block heights, anything a skeptic
would ask for)*

- 2026-08-07 — certificate path (pre-G0 live run): session verified end-to-end, operator
  published certificate, requestor + independent third read both verified it against the
  descriptor key. Blocks 3057376 / 3057397 / 3057399, agents 9427 / 9428.

- 2026-08-07 — **G0 passed** on local relay `127.0.0.1:18789`: host, payer kit,
  and requestor kit completed session `1889569c-6eeb-4672-8d02-3843c9579ec1`.
  Payer agent `9433` and requestor agent `9434` anchored proposal `3084524`,
  acceptance `3084545`, and acknowledgment `3084547`. The host's independent
  verifier printed `AUTHORIZED` with `paymentMoved: false`; both kits fetched,
  verified, and saved the signed closing certificate without self-adjudicating.
  The host then opened fresh session `4316566f-142f-48f1-bd5c-ee0ab87a949f`,
  and both discovery/current and monitor/current followed it. Fresh post-gate
  `npm run verify`: 908/908 tests and all structural invariants passed.

- 2026-08-07 — required legacy compatibility run passed after G0. `npm run demo`
  plus the requestor kit completed session
  `7bab845d-6396-4d01-8b41-2994f436d9af`; payer agent `9435`, requestor agent
  `9436`, blocks `3084711` / `3084732` / `3084734`. The independent verifier
  printed `AUTHORIZED`, the requestor verified and saved the certificate, and
  `paymentMoved` remained false.

- 2026-08-07 — **G1 passed** on the deployed relay at `44.249.47.220:8080`.
  The laptop host, remote payer kit, and laptop requestor kit completed session
  `d7bfb225-b812-4c52-beb1-2970abc9e660`; payer agent `9437`, requestor agent
  `9438`, blocks `3084959` / `3084968` / `3084982`. The host verifier printed
  `AUTHORIZED`; both kits verified and saved the signed closing certificate;
  `paymentMoved` remained false. The host reopened fresh session
  `736784e4-0212-40ad-a6b0-e19d7536d085`, and discovery/current plus
  monitor/current followed it. The rendered production monitor showed all three
  receipts, both identities in technical evidence, no `[object Object]`, and the
  verifier-owned verdict.

- 2026-08-07 — G1 payer race passed in the same session. Concurrent remote
  payer candidates published addresses `0xf3ac7090c2ddfd64cbfe0cd58cad588ad58a7866`
  and `0x5ae346c88ba4372406c048b8a05c2171ee957f85`. The host funded only the
  first address. The loser exited `ROLE_ALREADY_BOUND` on the seat-tagged
  payer funding record, printed “Nothing was spent,” and never published
  `party_ready` or registered an identity; only winner agent `9437` appears in
  the session roster.

- 2026-08-07 — B3 host-side deployment passed at external-repo commit
  `9f0075021bbfd471854a34c0082bfb282c2d2b7f` on `34.209.199.138`.
  `clockchain-mcp.service` is active with a successful exit; MCP is healthy,
  Caddy is running, only ports 80/443 are published, and host port 8080 is
  closed. An in-container `/health` check returned `status: ok`; the container
  sees the intended nonsecret settings (port 8080, 30 requests/minute, 10
  mints/hour, Clockchain node endpoint) and all three required SSM secrets are
  nonempty. No secret-bearing env file was written. A public forced-resolution
  HTTP request returned Caddy's HTTPS redirect, proving the security-group and
  listener path before DNS.

- 2026-08-08 — **B3 complete.** GoDaddy API write created
  `mcp-aws.clockchain.network A 34.209.199.138` at TTL 600 without changing the
  production record. Both GoDaddy nameservers plus Cloudflare and Google public
  resolvers returned the EIP. `https://mcp-aws.clockchain.network/health`
  returned `{"status":"ok"}` with a Let's Encrypt certificate whose only SAN
  is the test hostname (valid through 2026-11-06).

- 2026-08-08 — **B4 complete.** External-repo parity runner commit `fb4118b`
  compared the live GCP frontend with `mcp-aws.clockchain.network` using known
  immutable block `3084982` and reference
  `handshake-aws-parity-20260808-001`. Health, two token mints and quota
  movement, `get_timestamp`, `get_block`, AWS-write/GCP-read,
  GCP-write/AWS-read, and normalized write comparison all passed. Yang
  explicitly authorized `--allow-degraded true` for this run because validator
  count is not currently a gate; the runner remains fail-closed by default.
  Both frontends then returned the same exact anchored records:
  `3ddef6ff-54ec-46c1-9c58-e073b453d854` at block `3090566` and
  `cbbb5aab-acfe-427f-9a6a-39d371519e1c` at block `3090567`, each with
  SHA-256 `69db64ad68ad141cbdbb93ed4d26053f35c32bca49d458d0f9e8aee43de0b6cb`.
  Production DNS was still `136.68.167.2` throughout B4.

- 2026-08-08 — **B5 / GM complete.** GoDaddy production DNS is
  `mcp.clockchain.network A 34.209.199.138` at TTL 600. Both authoritative
  nameservers, Cloudflare, Google, and the local Node resolver returned the AWS
  EIP; HTTPS health passed with the production-only Let's Encrypt certificate.
  Post-cutover parity runner commit `95ea2e3` ran from the relay box so it had a
  fresh resolver and token-mint bucket. Both names hit the shared AWS process;
  all eight rows passed with reference
  `handshake-aws-cutover-parity-20260808-002`. Cross-name records
  `6b9257cf-7650-4d68-9dce-d42d087d42e2` at block `3091221` and
  `25f3a00a-462c-408d-82b2-a032d1d9af29` at block `3091222` were readable
  through production. The corrected four-part GM preflight passed at block
  `3091503`; the full legacy demo then completed session
  `64dd961d-25e9-42d9-9dcb-7d30a55dc302` with payer agent `9439`, requestor
  agent `9440`, proposal `3091583` / `02c23920-8d47-4c2e-9fd3-8b0b27047535`,
  acceptance `3091604` / `79ed7655-d2eb-46fd-8051-6c76b1e711d9`, and
  acknowledgment `3091625` / `de579f9f-798d-4061-8abf-3d9a4a1009e2`.
  The independent verifier returned `AUTHORIZED`; both sides verified the
  signed certificate; `paymentMoved` remained false. Fresh post-gate
  `npm run verify`: 910/910 tests and all structural invariants passed. GCP
  remains warm solely as the rollback target.

- 2026-08-08 — **B6 decision: defer the relay fold.** The existing Lightsail
  relay is healthy (`NRestarts=0`, about 19 MiB resident), and its 39 JSONL
  journals total only 1.6 MiB, but a correct move still requires a write freeze,
  exact state transfer, a cross-repository relay image/compose path, Caddy and
  installer changes, and another production DNS change beyond the two batched
  MCP visits. None of that improves G2 or G3: the P2 host can use the existing
  relay through `HANDSHAKE_RELAY`, and the plan explicitly accepts Lightsail as
  the end state. Revisit only as a separate post-P4 maintenance change.

- 2026-08-08 — **P2 / G2 complete.** Handshake commit `fbb054d` supplies the
  Node 22 non-root host image; external-repo commits `86637a2` and `c73a3a4`
  add the third compose service, SSM materialization, and the systemd-owned
  checkout fix. The EC2 role can read only `/clockchain/mcp/*` and
  `/clockchain/host/*`; all four host files were hash-matched to SSM without
  exposing values, are mode 0600, and are mounted read-only at `/app/keys`.
  With no handshake process on the laptop, the AWS host and two transient
  party services on the relay machine completed session
  `c5944663-9419-47ea-98c2-b75a054c2fdc`. Payer agent `9443` and requestor
  agent `9444` anchored proposal `3093515` /
  `44a420e0-9b1b-4a62-87d5-6c8b4336dae3`, acceptance `3093535` /
  `7f339b7e-9be4-4662-aea2-c996322d6b46`, and acknowledgment `3093537` /
  `b242b010-69ce-4d7d-b70d-440282d05585`. The AWS host's verifier returned
  `AUTHORIZED`; both remote kits verified and saved the signed certificate;
  `paymentMoved` remained false. The host loop opened session
  `2e6a116b-7f69-4ebc-8931-1a983faafbd1`. A manual
  `docker restart clockchain-mcp-host-1` changed its start time from
  `08:10:42Z` to `08:14:13Z`, returned to `running`, and opened fresh session
  `69071193-f140-494c-bb60-70b654160a15`; production MCP health stayed green.

## Migration inventory

*(plan §B0's table gets filled in here — every row, even when the answer is "none")*

Inventory source: `clockchain-developer-tools` commit
`bef177bdf93f1d36fbbe0a2a787121518eb3d3eb` (2026-08-07).

| Question | Answer |
|---|---|
| Language/runtime + listen port | TypeScript / Node ESM. The container runs Node 20 and `packages/mcp-server/dist/index.js`. HTTP listens on `PORT`, then `MCP_PORT`, then `3000`; Cloud Run and the Dockerfile use `8080`. |
| How does it reach the chain node (`node.clockchain.network`)? Pull or push? | Outbound request/response from MCP to `CLOCKCHAIN_ENDPOINT` (default `https://node.clockchain.network`): GETs for reads and POSTs for writes. The node does not push inbound to MCP. |
| Where do token quotas live (memory / file / external store)? | Static tokens are configuration; self-serve tokens are stateless HMAC tokens. Mint quotas and log-credit budgets are in-memory, per-process maps. |
| Where do receipts/ledger ids live? | The caller receives receipt payloads; ledger records and ids live on Clockchain and are read through its `/ledger` / chain APIs. The MCP has no receipt database. |
| Env vars + secrets the container needs (names, where GCP stores them) | Required core values: `CLOCKCHAIN_API_KEY`, `CLOCKCHAIN_CLIENT_ID`, `CLOCKCHAIN_WALLET_ID`; hosted configuration also sets `MCP_TRANSPORT`, `MCP_REQUIRE_AUTH`, `MCP_RATE_PER_MIN`, `MCP_LOG_BUDGET`, `MCP_TOKEN_MINT_PER_HOUR`, `MCP_TOKEN_TTL_DAYS`, and `CLOCKCHAIN_ENDPOINT`. Optional chain settings: `EVM_RPC_URL`, `ERC8004_CHAIN`, `ERC8004_REGISTRY_ADDRESS`. GCP Secret Manager supplies `clockchain-api-key`, `mcp-auth-tokens`, and `mcp-token-signing-secret`; B1 replaces those with SSM SecureStrings. |
| Does it use ANY GCP-managed service (Firestore, GCS, Cloud SQL, Memorystore, Pub/Sub)? | Deployment uses Cloud Run, Cloud Build, Artifact Registry, Secret Manager, Cloud Armor, and Cloud Logging/Monitoring. It uses none of Firestore, GCS, Cloud SQL, Memorystore, Pub/Sub, or any other application datastore. Default session/account state is memory; optional `MCP_SESSION_FILE` is local JSON; the documented DynamoDB store is not implemented. The B0 stateful-data STOP trigger did not fire. |
| Does it stream (SSE/websocket) on the MCP endpoint? | Streamable HTTP can return SSE and clients advertise `application/json, text/event-stream`. No websocket server was found. |
| Health endpoint | Unauthenticated `GET /health` and `GET /healthz`, returning `{"status":"ok"}` before auth or gateway access. |

### B2 provisioned host (2026-08-07)

| Resource | ID / value |
|---|---|
| AWS account / region | `570035913370` / `us-west-2` |
| EC2 instance | `i-0d6765d143da7e1ea` — `t3.small`, running, status checks green |
| Ubuntu AMI | `ami-0ac74609c6396bed3` — Canonical Ubuntu 24.04 LTS amd64 gp3 |
| VPC / subnet / AZ | `vpc-0aa12e33b416f8a90` / `subnet-0098c0ad31cc55dab` / `us-west-2d` |
| Private / Elastic IP | `172.31.50.64` / `34.209.199.138` |
| EIP allocation / association | `eipalloc-01233aceb0e395e04` / `eipassoc-04b63a9427c4addfb` |
| Security group | `sg-019cf9e090977a49f` (`clockchain-mcp-sg`): 80/443 public; 22 from `172.12.143.34/32` only |
| Root volume | `vol-0d84c8180aa7d2dff` — 20 GiB encrypted gp3, delete on termination |
| EC2 key pair | `clockchain-mcp` / `key-0cf030c5ba260d457`; private key at `~/.ssh/clockchain-mcp.pem` mode 0600 |
| IAM role | `arn:aws:iam::570035913370:role/clockchain-mcp-ec2-role` |
| Instance profile | `arn:aws:iam::570035913370:instance-profile/clockchain-mcp-instance-profile` |
| Inline role policy | `clockchain-mcp-ssm-parameter-read`: `ssm:GetParameter` on only `arn:aws:ssm:us-west-2:570035913370:parameter/clockchain/mcp/*` and `arn:aws:ssm:us-west-2:570035913370:parameter/clockchain/host/*` |
| SSM verification parameter | `/clockchain/mcp/PING` (`SecureString`, `alias/aws/ssm`) |
| SSM application secrets | `/clockchain/mcp/CLOCKCHAIN_API_KEY`, `/clockchain/mcp/MCP_AUTH_TOKENS`, `/clockchain/mcp/MCP_TOKEN_SIGNING_SECRET` (`SecureString`; byte-for-byte hashes verified against their GCP Secret Manager sources without exposing values) |
| SSM host secrets | `/clockchain/host/FUNDING_WALLET_JSON`, `/clockchain/host/FUNDING_WALLET_PUBLIC_JSON`, `/clockchain/host/FUNDING_PASSWORD`, `/clockchain/host/CLOCKCHAIN_TOKEN` (`SecureString`; byte-for-byte hashes verified against the private source files without exposing values) |

Bootstrap evidence: cloud-init completed; Docker, Compose, AWS CLI v2, git, and jq are
installed; `docker run --rm hello-world` passed; the instance read the PING parameter
through its role; `/home/ubuntu/.aws` remains absent after the literal read; no long-lived
AWS credentials or config file exists; IMDSv2 is required with hop limit 2. Provisioning
sources are `clockchain-developer-tools` commits `610d519` and `11b9162`.

### B3 deployed stack (2026-08-08)

| Item | Value / evidence |
|---|---|
| Source branch / commit | `codex/aws-migration` / `9f0075021bbfd471854a34c0082bfb282c2d2b7f` |
| Remote checkout | `/opt/clockchain-mcp/app`, clean clone of the source commit |
| Service | `clockchain-mcp.service`: active, `Result=success`, `ExecMainStatus=0` |
| Containers | `clockchain-mcp-mcp-1` healthy; `clockchain-mcp-caddy-1` running |
| Application listeners / SSH | Caddy publishes 80/443; SSH 22 remains source-restricted by the locked security group; no host listener on 8080 |
| Public HTTPS | `https://mcp-aws.clockchain.network/health` returns `{"status":"ok"}` with a valid hostname-only Let's Encrypt certificate |
| DNS | GoDaddy authoritative nameservers and public resolvers return `34.209.199.138` for both test and production names at TTL 600; GCP `136.68.167.2` remains the warm rollback target |

### P2 host deployment (2026-08-08)

| Item | Value / evidence |
|---|---|
| Handshake source | `codex/handshake-build` / `fbb054d5ec9b03a483583c683a10b3cf44e8557a`, clean checkout at `/opt/clockchain-host/app` |
| Deploy source | `codex/aws-migration` / `c73a3a426d9148e18dd0744e0a1992c06d2fdd7c`, clean checkout at `/opt/clockchain-mcp/app` |
| Containers | `clockchain-mcp-mcp-1` healthy; `clockchain-mcp-caddy-1` running; `clockchain-mcp-host-1` running as non-root `node` with no published port |
| Host secret files | `/run/clockchain-host-secrets/{funding-wallet.json,funding-wallet.public.json,funding.password,clockchain.token}`; owner `ubuntu:ubuntu` (UID/GID 1000), mode 0600, exact SSM hashes verified |
| Runtime mounts | Host secrets bind-mounted read-only at `/app/keys`; named volume `clockchain-mcp_host_runs` mounted at `/app/runs` |
| Restart evidence | Manual container restart changed `StartedAt`, preserved production MCP health, and advanced relay `discovery/current` from session `2e6a116b-7f69-4ebc-8931-1a983faafbd1` to `69071193-f140-494c-bb60-70b654160a15` |
